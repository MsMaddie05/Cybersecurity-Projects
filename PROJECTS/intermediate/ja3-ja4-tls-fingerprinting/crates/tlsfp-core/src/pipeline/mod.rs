// ©AngelaMos | 2026
// mod.rs

//! The passive fingerprinting pipeline: frames in, fingerprint events out.
//!
//! The stages are deliberately separable. A [`PacketSource`] yields raw link
//! layer frames from a capture file or, later, a live interface. The decoder
//! strips the frame down to a TCP segment. The flow table reassembles each
//! direction of each conversation into a contiguous byte stream, surviving
//! reordering, retransmission, and overlap. The protocol layer watches each
//! stream until it recognizes a TLS flight or an HTTP request head and emits
//! fingerprints. Nothing in here touches a network interface, so the whole
//! pipeline runs byte exact in tests against vendored captures.

pub mod decode;
pub mod event;
pub mod flow;
pub mod source;
pub mod tls;

use std::collections::HashMap;

use serde::Serialize;

use crate::ja4t::ja4t;
use crate::pipeline::decode::{Skip, decode_frame};
use crate::pipeline::event::{FingerprintEvent, StreamEvent};
use crate::pipeline::flow::{FlowKey, PushOutcome, ReassemblyLimits, StreamReassembler};
use crate::pipeline::source::{PacketSource, RawFrame, SourceError};
use crate::pipeline::tls::StreamProtocol;

/// Tuning knobs for the pipeline.
///
/// The defaults are sized for handshake harvesting: generous enough that a
/// fat certificate chain or a multi segment ClientHello always fits, small
/// enough that an adversarial capture cannot turn the flow table into a
/// memory bomb.
#[derive(Debug, Clone, Copy)]
pub struct PipelineConfig {
    /// Flows tracked at once before the table sheds its oldest entries.
    pub max_flows: usize,
    /// A flow untouched for this long is eligible for eviction.
    pub idle_timeout_nanos: u64,
    /// Contiguous bytes kept per direction.
    pub max_assembled_bytes: usize,
    /// Out of order bytes parked per direction.
    pub max_pending_bytes: usize,
    /// Out of order segments parked per direction.
    pub max_pending_segments: usize,
}

impl PipelineConfig {
    pub const DEFAULT_MAX_FLOWS: usize = 65_536;
    pub const DEFAULT_IDLE_TIMEOUT_NANOS: u64 = 60 * 1_000_000_000;
    pub const DEFAULT_MAX_ASSEMBLED_BYTES: usize = 256 * 1024;
    pub const DEFAULT_MAX_PENDING_BYTES: usize = 256 * 1024;
    pub const DEFAULT_MAX_PENDING_SEGMENTS: usize = 128;

    fn limits(&self) -> ReassemblyLimits {
        ReassemblyLimits {
            max_assembled_bytes: self.max_assembled_bytes,
            max_pending_bytes: self.max_pending_bytes,
            max_pending_segments: self.max_pending_segments,
        }
    }
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            max_flows: Self::DEFAULT_MAX_FLOWS,
            idle_timeout_nanos: Self::DEFAULT_IDLE_TIMEOUT_NANOS,
            max_assembled_bytes: Self::DEFAULT_MAX_ASSEMBLED_BYTES,
            max_pending_bytes: Self::DEFAULT_MAX_PENDING_BYTES,
            max_pending_segments: Self::DEFAULT_MAX_PENDING_SEGMENTS,
        }
    }
}

/// What the pipeline saw, for the operator and for the miss rate honesty
/// check: a fingerprinting tool that cannot say what it failed to read is a
/// tool whose silence gets mistaken for absence.
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct Counters {
    pub frames: u64,
    pub bytes: u64,
    pub tcp_segments: u64,
    pub skipped_unsupported_link_type: u64,
    pub skipped_not_ip: u64,
    pub skipped_not_tcp: u64,
    pub skipped_malformed: u64,
    pub flows_created: u64,
    pub flows_evicted_idle: u64,
    pub flows_evicted_pressure: u64,
    pub segments_dropped: u64,
    pub events: u64,
    pub streams_capped: u64,
    pub unfinished_tls_streams: u64,
}

/// One direction of one tracked flow.
struct StreamHalf {
    reassembler: StreamReassembler,
    protocol: StreamProtocol,
    syn_fingerprint_emitted: bool,
}

impl StreamHalf {
    fn new(limits: ReassemblyLimits) -> Self {
        Self {
            reassembler: StreamReassembler::new(limits),
            protocol: StreamProtocol::Undecided,
            syn_fingerprint_emitted: false,
        }
    }
}

struct FlowState {
    halves: [StreamHalf; 2],
    last_seen_nanos: u64,
}

impl FlowState {
    fn new(limits: ReassemblyLimits) -> Self {
        Self {
            halves: [StreamHalf::new(limits), StreamHalf::new(limits)],
            last_seen_nanos: 0,
        }
    }

    fn finished(&self) -> bool {
        self.halves.iter().all(|h| h.protocol.finished())
    }
}

/// The passive fingerprinting engine.
///
/// Feed it frames, take events out through the sink closure. The pipeline is
/// synchronous and single threaded by design: one pipeline owns its flow
/// table outright, and running one per worker beats sharing a locked table
/// between workers.
pub struct Pipeline {
    config: PipelineConfig,
    flows: HashMap<FlowKey, FlowState>,
    counters: Counters,
}

impl Pipeline {
    #[must_use]
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            config,
            flows: HashMap::new(),
            counters: Counters::default(),
        }
    }

    #[must_use]
    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    /// Drains a source through the pipeline, sending every event to `sink`.
    pub fn run<S: PacketSource>(
        &mut self,
        source: &mut S,
        mut sink: impl FnMut(FingerprintEvent),
    ) -> Result<(), SourceError> {
        while let Some(frame) = source.next_frame()? {
            self.feed(&frame, &mut sink);
        }
        self.finish();
        Ok(())
    }

    /// Processes one captured frame.
    pub fn feed(&mut self, frame: &RawFrame<'_>, sink: &mut impl FnMut(FingerprintEvent)) {
        self.counters.frames += 1;
        self.counters.bytes += frame.data.len() as u64;

        let segment = match decode_frame(frame.link_type, frame.data) {
            Ok(segment) => segment,
            Err(skip) => {
                match skip {
                    Skip::UnsupportedLinkType => {
                        self.counters.skipped_unsupported_link_type += 1;
                    }
                    Skip::NotIp => self.counters.skipped_not_ip += 1,
                    Skip::NotTcp => self.counters.skipped_not_tcp += 1,
                    Skip::Malformed => self.counters.skipped_malformed += 1,
                }
                return;
            }
        };
        self.counters.tcp_segments += 1;

        let (key, direction) = FlowKey::from_pair(segment.src, segment.dst);
        if !self.flows.contains_key(&key) {
            if self.flows.len() >= self.config.max_flows {
                self.evict(frame.ts_nanos);
            }
            self.flows.insert(key, FlowState::new(self.config.limits()));
            self.counters.flows_created += 1;
        }
        let Some(flow) = self.flows.get_mut(&key) else {
            return;
        };
        flow.last_seen_nanos = flow.last_seen_nanos.max(frame.ts_nanos);

        let (src, dst) = direction.addresses(&key);
        let half = &mut flow.halves[direction.index()];

        if !half.syn_fingerprint_emitted {
            if let Some(input) = &segment.syn_fingerprint {
                half.syn_fingerprint_emitted = true;
                let fingerprint = ja4t(input);
                let event = if segment.tcp.flags.ack() {
                    StreamEvent::TcpSynAck { ja4ts: fingerprint }
                } else {
                    StreamEvent::TcpSyn { ja4t: fingerprint }
                };
                self.counters.events += 1;
                sink(FingerprintEvent {
                    ts_nanos: frame.ts_nanos,
                    src,
                    dst,
                    event,
                });
            }
        }

        if segment.tcp.flags.syn() {
            half.reassembler.anchor(segment.tcp.seq.wrapping_add(1));
        }

        let payload_seq = if segment.tcp.flags.syn() {
            segment.tcp.seq.wrapping_add(1)
        } else {
            segment.tcp.seq
        };
        let outcome = half.reassembler.push(payload_seq, segment.payload);
        if outcome == PushOutcome::Dropped {
            self.counters.segments_dropped += 1;
        }

        if outcome == PushOutcome::Grew {
            let mut emitted = 0u64;
            tls::advance(&mut half.protocol, half.reassembler.data(), &mut |event| {
                emitted += 1;
                sink(FingerprintEvent {
                    ts_nanos: frame.ts_nanos,
                    src,
                    dst,
                    event,
                });
            });
            self.counters.events += emitted;
            if half.protocol.finished() && !half.reassembler.released() {
                half.reassembler.release();
            }
        }
    }

    /// Settles the books at end of capture.
    ///
    /// Streams that were recognized as TLS but never produced a complete
    /// handshake message are counted: each one is a handshake the capture
    /// clipped, which is exactly the number an operator needs before trusting
    /// an absence of fingerprints.
    pub fn finish(&mut self) {
        for flow in self.flows.values() {
            for half in &flow.halves {
                if half.protocol.unfinished_tls() {
                    self.counters.unfinished_tls_streams += 1;
                }
                if half.reassembler.capped() {
                    self.counters.streams_capped += 1;
                }
            }
        }
        self.flows.clear();
    }

    /// Sheds flows when the table is full: everything idle past the timeout
    /// or fully harvested goes, and if nothing qualifies, the single stalest
    /// flow goes, so the table never refuses a brand new conversation in
    /// favor of a dead one.
    fn evict(&mut self, now_nanos: u64) {
        let timeout = self.config.idle_timeout_nanos;
        let idle: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, flow)| {
                now_nanos.saturating_sub(flow.last_seen_nanos) > timeout || flow.finished()
            })
            .map(|(key, _)| *key)
            .collect();

        if idle.is_empty() {
            let stalest = self
                .flows
                .iter()
                .min_by_key(|(_, flow)| flow.last_seen_nanos)
                .map(|(key, _)| *key);
            if let Some(key) = stalest {
                self.drop_flow(key);
                self.counters.flows_evicted_pressure += 1;
            }
            return;
        }

        for key in idle {
            self.drop_flow(key);
            self.counters.flows_evicted_idle += 1;
        }
    }

    fn drop_flow(&mut self, key: FlowKey) {
        if let Some(flow) = self.flows.remove(&key) {
            for half in &flow.halves {
                if half.protocol.unfinished_tls() {
                    self.counters.unfinished_tls_streams += 1;
                }
                if half.reassembler.capped() {
                    self.counters.streams_capped += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Pipeline, PipelineConfig};
    use crate::pipeline::event::FingerprintEvent;
    use crate::pipeline::source::RawFrame;
    use etherparse::PacketBuilder;

    fn tcp_frame(src: ([u8; 4], u16), dst: ([u8; 4], u16), seq: u32, payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4(src.0, dst.0, 64)
            .tcp(src.1, dst.1, seq, 64240);
        let mut out = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut out, payload).unwrap();
        out
    }

    fn feed_all(pipeline: &mut Pipeline, frames: &[Vec<u8>]) -> Vec<FingerprintEvent> {
        let mut events = Vec::new();
        for (i, data) in frames.iter().enumerate() {
            let frame = RawFrame {
                ts_nanos: u64::try_from(i).unwrap() * 1_000_000,
                link_type: 1,
                data,
            };
            pipeline.feed(&frame, &mut |e| events.push(e));
        }
        events
    }

    #[test]
    fn http_request_split_across_segments_fingerprints_once() {
        let client = ([10, 0, 0, 1], 40000);
        let server = ([10, 0, 0, 2], 80);
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let (a, b) = request.split_at(20);

        let frames = vec![
            tcp_frame(client, server, 1000, a),
            tcp_frame(client, server, 1000 + u32::try_from(a.len()).unwrap(), b),
        ];

        let mut pipeline = Pipeline::new(PipelineConfig::default());
        let events = feed_all(&mut pipeline, &frames);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].src.to_string(), "10.0.0.1:40000");
        assert_eq!(pipeline.counters().tcp_segments, 2);
    }

    #[test]
    fn out_of_order_delivery_after_a_syn_still_fingerprints() {
        let client = ([10, 0, 0, 1], 40001);
        let server = ([10, 0, 0, 2], 80);
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let (a, b) = request.split_at(20);

        let syn = {
            let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
                .ipv4(client.0, server.0, 64)
                .tcp(client.1, server.1, 999, 64240)
                .syn();
            let mut out = Vec::with_capacity(builder.size(0));
            builder.write(&mut out, &[]).unwrap();
            out
        };

        let frames = vec![
            syn,
            tcp_frame(client, server, 1000 + u32::try_from(a.len()).unwrap(), b),
            tcp_frame(client, server, 1000, a),
        ];

        let mut pipeline = Pipeline::new(PipelineConfig::default());
        let events = feed_all(&mut pipeline, &frames);
        assert_eq!(events.len(), 2);
        assert!(events[0].to_string().contains("tcp_syn ja4t="));
        assert!(events[1].to_string().contains("http_request"));
    }

    #[test]
    fn pressure_eviction_keeps_the_table_bounded() {
        let config = PipelineConfig {
            max_flows: 4,
            ..PipelineConfig::default()
        };
        let mut pipeline = Pipeline::new(config);

        let mut frames = Vec::new();
        for i in 0..8u16 {
            let port = 40000 + i;
            frames.push(tcp_frame(
                ([10, 0, 0, 1], port),
                ([10, 0, 0, 2], 80),
                1,
                b"x",
            ));
        }
        feed_all(&mut pipeline, &frames);

        assert_eq!(pipeline.counters().flows_created, 8);
        assert!(pipeline.counters().flows_evicted_pressure >= 4);
    }
}

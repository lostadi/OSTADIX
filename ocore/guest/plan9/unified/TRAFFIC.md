# Resident-service idle traffic

The 2026-11-06 service retains one read-only service-directory descriptor,
rewinds it before enumeration, and backs off idle sleeps from 50 to 100, 200,
then 250 ms. A newly admitted invocation resets the next sleep to 50 ms.
Directory rewind/read errors stop the instance. The descriptor is close-on-exec
so original executed programs do not inherit it. The independent in-flight
cancellation/deadline loop still targets 50 ms.

Rewinding enumerates the current directory; neither listings nor directory qid
versions substitute for checking submission inside an existing request
directory. Accepted IDs still cannot replay after their persisted claims are
removed. Native authority, request framing, results, cancellation and required
domain recovery are unchanged. The synthetic UART remains trapped/emulated.

The production native-store fixture executes the service's actual scan loop
and delay function with mount-client hooks. Its matched five-second policy
workload uses 500 requests / 21,700 wire bytes with the old reopen-and-50-ms
loop, versus 46 requests / 3,076 bytes with the new loop, including initial
walk/open. It also proves fresh create/late-submit/remove/create enumeration,
revoked-fid errors, and the 50-ms reset after activity. Restoring the old loop
in a private negative control fails the traffic assertion. These are actual
native protocol calls under simulated policy time, not a guest CPU benchmark.

New original 7c/7l service and full kernel builds passed, including PAQ-only
original source compilation. All 22 original-service behavior cases were rerun
on the new bytes, plus foreground-console/resident-compiler coexistence.
Five actual original-filesystem echo trials measured admission at 65–90 ms
with build 7 and 80–190 ms with the new service. This illustrates the idle
latency tradeoff; 250 ms is a polling target, not a hard scheduling guarantee.
The private original-filesystem tests do not measure native shared-transport
latency or establish whole-system efficiency.

Retained evidence:

- New build: `/home/ustad/.cache/okernel-plan9-traffic-20261106-build-2/result.json`.
- Aggregate: `/home/ustad/.cache/okernel-plan9-traffic-20261106-qualification-1/result.json`.
- Native fixture: `/home/ustad/.cache/okernel-plan9-traffic-native-final-20261106-3io_pocf/result.json`.
- Original latency: `okernel-plan9-traffic-20261106-latency-before-1` and
  `okernel-plan9-traffic-20261106-latency-after-1` under `/home/ustad/.cache`.

The prior build 7 and its evidence remain unchanged. The interrupted private
build 1 is retained as unsuccessful; build 2 includes the descriptor's
close-on-exec correction. Unified runtime admission, native idle scheduling,
whole-domain interruption recovery, and ISO qualification remain separate
coordinator gates.

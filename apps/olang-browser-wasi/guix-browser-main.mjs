import { startGuixBrowserSession } from "./guix-session-runner.mjs";

const element = id => document.getElementById(id);
const terminal = element("terminal");
const status = element("status");
let session, controller, starting = false, consoleReady = false, pending = new Uint8Array(), retry;
let decoders;
function enable(running) {
  for (const id of ["command", "send", "eof"]) element(id).disabled = !running || !consoleReady;
  element("stop").disabled = !starting && !running;
  element("stop").textContent = starting ? "Cancel loading" : "Force stop";
  element("start").disabled = starting || running;
}
function append({fd, bytes}) {
  const text = decoders[fd].decode(bytes, {stream:true});
  // The terminal is plain text with bounded scrollback, never HTML from Guix.
  terminal.textContent = (terminal.textContent + text).slice(-262144);
  terminal.scrollTop = terminal.scrollHeight;
  // Instantiating Wasm is not Linux/Guix readiness. A prompt may span several
  // output frames; inspect the bounded accumulated text before enabling input.
  if (!consoleReady && /(?:^|[\r\n])guix> /.test(terminal.textContent)) {
    consoleReady = true;
    enable(Boolean(session));
    status.textContent = "Guix is accepting commands. Type exit for a clean saved shutdown.";
  }
}
function flushInput() {
  clearTimeout(retry);
  if (!session) return false;
  if (!pending.length) return true;
  try {
    pending = pending.subarray(session.sendInput(pending));
    if (pending.length) retry = setTimeout(flushInput, 16);
    return true;
  } catch (error) { status.textContent = error.message; pending = new Uint8Array(); return false; }
}
function send(bytes) {
  if (!session || !consoleReady) return false;
  if (pending.length + bytes.length > 8192) {
    status.textContent = "Input queue is full; wait for Guix to consume the previous command.";
    return false;
  }
  const next = new Uint8Array(pending.length + bytes.length);
  next.set(pending); next.set(bytes, pending.length); pending = next;
  return flushInput();
}
element("start").onclick = async () => {
  if (starting || session) return;
  starting = true; consoleReady = false; controller = new AbortController(); enable(false);
  terminal.textContent = "";
  decoders = {1:new TextDecoder(), 2:new TextDecoder()};
  status.textContent = "Loading and verifying the packaged ExecutionPlan and runtime assets…";
  try {
    // Persistence permission is a browser request, not a guarantee against
    // user-cleared site data or exhausted physical disk space.
    // Do not leave Cancel loading blocked behind a browser permission prompt.
    // The request is advisory: OPFS state remains origin-private even if the
    // browser declines persistence, and clearing site data still removes it.
    Promise.resolve(navigator.storage?.persist?.()).catch(() => {});
    session = await startGuixBrowserSession({baseUrl:new URL("./", import.meta.url),
      signal:controller.signal, onOutput:append, onStatus:text => { status.textContent = text; }});
    starting = false; enable(true);
    const result = await session.done;
    status.textContent = `Guix exited ${result.exitCode}. Browser disk saved cleanly. You can start it again.`;
  } catch (error) {
    status.textContent = `Not completed: ${error?.message ?? error}`;
  } finally {
    session = undefined; controller = undefined; starting = false; consoleReady = false;
    pending = new Uint8Array(); clearTimeout(retry); enable(false);
  }
};
element("command-form").onsubmit = event => {
  event.preventDefault();
  const input = element("command");
  const bytes = new TextEncoder().encode(input.value + "\n");
  if (bytes.length > 4096) { status.textContent = "Commands are limited to 4095 UTF-8 bytes."; return; }
  if (send(bytes)) input.value = "";
};
element("eof").onclick = () => send(new Uint8Array([4]));
element("stop").onclick = () => {
  if (starting && !session) controller?.abort();
  else if (session && confirm("Force stop without a clean save? The disk will require recovery. Use exit at guix> for a normal saved shutdown.")) session.stop();
};
terminal.onkeydown = event => {
  if (!session || !event.ctrlKey) return;
  if (event.key.toLowerCase() === "d" || event.key.toLowerCase() === "c") {
    event.preventDefault(); send(new Uint8Array([event.key.toLowerCase() === "d" ? 4 : 3]));
  }
};
window.addEventListener("beforeunload", event => {
  if (session || starting) { event.preventDefault(); event.returnValue = ""; }
});
enable(false);

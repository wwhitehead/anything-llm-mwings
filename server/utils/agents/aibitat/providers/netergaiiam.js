/**
 * NeterGaiiaM aibitat agent provider — wraps the NeterGaiiaMLLM AiProvider
 * (which proxies to the AsAManThinks platform's /inference/turbo/chat) so
 * agent flows (@agent and any aibitat-routed completions) can use the same
 * tier-aware billing pool and Wings/TERA prompt that the regular workspace
 * chat uses.
 *
 * The platform endpoint is OpenAI-shaped at the *response* layer
 * (object: "chat.completion"), but its request path is /inference/turbo/chat
 * — not /v1/chat/completions — so we cannot directly point the OpenAI SDK
 * at it. Instead we delegate to NeterGaiiaMLLM.getChatCompletion which
 * already speaks the platform's request shape, and we run UnTooled for
 * tool-calling fallback (the platform does not currently expose native
 * OpenAI-style tool calling).
 */

const Provider = require("./ai-provider.js");
const InheritMultiple = require("./helpers/classes.js");
const UnTooled = require("./helpers/untooled.js");
const { NeterGaiiaMLLM } = require("../../../AiProviders/netergaiiam");

class NeterGaiiaMProvider extends InheritMultiple([Provider, UnTooled]) {
  model;

  constructor(config = {}) {
    super();
    const { model = null } = config;
    this.model =
      model || process.env.NETERGAIIAM_MODEL || "netergaiiam-default";
    this._llm = new NeterGaiiaMLLM(null, this.model);
    this.verbose = true;
  }

  get client() {
    // No OpenAI SDK client; aibitat's UnTooled helpers use the bound
    // handlers below rather than reading this.client directly.
    return null;
  }

  get supportsAgentStreaming() {
    // The platform supports SSE streaming, but the aibitat agent loop only
    // needs final text + parsed tool-calls. UnTooled's non-streaming complete
    // path is sufficient and avoids re-implementing SSE adapters here.
    return false;
  }

  supportsNativeToolCalling() {
    // Platform does not yet expose OpenAI-style tool calling; UnTooled
    // prompt-based tool selection is the right fallback.
    return false;
  }

  async #handleFunctionCallChat({ messages = [] }) {
    try {
      const result = await this._llm.getChatCompletion(messages, {
        temperature: 0,
      });
      return result?.output?.textResponse ?? result?.textResponse ?? null;
    } catch (e) {
      console.error("NeterGaiiaMProvider chat error", e.message);
      return null;
    }
  }

  async stream(messages, functions = [], eventHandler = null) {
    return await UnTooled.prototype.stream.call(
      this,
      messages,
      functions,
      // UnTooled.stream expects a streaming handler; reuse the non-stream
      // path here — the platform's response is consumed as a single chunk
      // because supportsAgentStreaming === false anyway.
      this.#handleFunctionCallChat.bind(this),
      eventHandler
    );
  }

  async complete(messages, functions = []) {
    return await UnTooled.prototype.complete.call(
      this,
      messages,
      functions,
      this.#handleFunctionCallChat.bind(this)
    );
  }

  getCost(_usage) {
    // Platform handles billing per-tier; agent-side cost reporting is N/A.
    return 0;
  }
}

module.exports = NeterGaiiaMProvider;

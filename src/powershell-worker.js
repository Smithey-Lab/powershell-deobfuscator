import { analyze } from "./powershell-engine.js";
self.onmessage = async ({ data }) => {
  try {
    self.postMessage({ result: await analyze(data) });
  } catch (error) {
    self.postMessage({ error: error.message });
  }
};

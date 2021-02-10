// @ts-ignore
import { Renderer } from "./render";
import WhoamiProcess from "./WhoamiProcess";

(async () => {
  await main.call(globalThis);
})();

async function main(this: { document: Document }) {
  const render = Renderer(document.querySelector("app") || document.body);
  WhoamiProcess.call(this, { render });
}

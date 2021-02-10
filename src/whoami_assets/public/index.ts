// @ts-ignore
import { Renderer } from "./render";
import WhoamiActor from "./WhoamiActor";

(async () => {
  await main.call(globalThis);
})();

async function main(this: { document: Document }) {
  console.debug("ic-whoami main");
  const render = Renderer(document.querySelector("app") || document.body);
  WhoamiActor.call(this, { render });
}

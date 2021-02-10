import { Renderer } from "./render";
import WhoamiProcess from "./WhoamiProcess";

(async () => {
  await main.call(globalThis);
})();

/**
 * ic-whoami main.
 * It should run some processes:
 * * WhoamiProcess - authenticate the end-user, then render the resulting Identity
 * @param this Window
 * @param this.document - Doocument to render within and use for events
 */
async function main(this: { document: Document }) {
  const { document } = this;
  const render = Renderer(document.querySelector("app") || document.body);
  WhoamiProcess.call(this, { render });
}

// @ts-ignore
import { Renderer } from "./render";
import WhoamiActor from "./WhoamiActor";

WhoamiActor({
    render: Renderer(document.querySelector('app') || document.body),
});

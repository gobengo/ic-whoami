/**
 * A renderer can be used to change what appears inside a parentElement.
 * Just re-call the render function with a new child node to re-render.
 * @param parentNode - Node that will have its children managed by this.
 */
export function Renderer(parentNode: Node): Render {
  return (el: Element | Text) => {
    while (parentNode.firstChild) parentNode.firstChild.remove();
    parentNode.appendChild(el);
  };
}

export type Render = (el: Element | Text) => void;

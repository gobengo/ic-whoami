export function Renderer(parentNode: Node): Render {
  return (el: Element | Text) => {
    while (parentNode.firstChild) parentNode.firstChild.remove();
    parentNode.appendChild(el);
  };
}

export type Render = (el: Element | Text) => void;

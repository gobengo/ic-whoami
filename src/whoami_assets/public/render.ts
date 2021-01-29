export function Renderer(parentNode: Node) {
    return (el: Element) => {
        while (parentNode.firstChild) parentNode.firstChild.remove();
        parentNode.appendChild(el);
    }
}

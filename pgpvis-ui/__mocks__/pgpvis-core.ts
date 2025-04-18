export class Node {
  readonly text: string;
  readonly children: Node[];
  readonly offset: number | undefined;
  readonly length: number | undefined;

  constructor(
    text: string,
    children: Node[] = [],
    offset?: number,
    length?: number,
  ) {
    this.text = text;
    this.children = children;
    this.offset = offset;
    this.length = length;
  }

  public free() {}
}

export class ParseOutput {
  readonly bytes: Uint8Array;
  readonly nodes: Node[];

  constructor(bytes?: Uint8Array, nodes: Node[] = []) {
    this.bytes = bytes || new Uint8Array();
    this.nodes = nodes;
  }

  public free() {}
}

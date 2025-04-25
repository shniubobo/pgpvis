export function parse(
  _options: ParseOptions,
  message: Uint8Array,
): ParseOutput {
  if (message.length === 0) {
    throw new Error("failed to read message");
  }
  return new ParseOutput(new Uint8Array(1), [new Node("1")]);
}

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

export class ParseOptions {
  public constructor(public dearmor: boolean) {}

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

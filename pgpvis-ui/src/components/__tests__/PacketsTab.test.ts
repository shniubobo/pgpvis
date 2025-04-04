import { render } from "@testing-library/vue";
import { describe, expect, test } from "vitest";

import PacketsTab from "../PacketsTab.vue";

describe.concurrent.skip("Nodes should match snapshots", () => {
  describe("13: User ID", () => {
    test("@", () => {
      const { container } = render(PacketsTab, {
        props: {
          packets: [
            {
              offset: 0,
              length: 25,
              inner: {
                header: {
                  offset: 0,
                  length: 2,
                  inner: {
                    format: "OpenPGP",
                    ctb: {
                      offset: 0,
                      length: 1,
                      inner: {
                        type_id: 13,
                      },
                    },
                    length: {
                      offset: 1,
                      length: 1,
                      inner: {
                        encoding: "Full",
                        length: 23,
                      },
                    },
                  },
                },
                body: {
                  offset: 2,
                  length: 23,
                  inner: {
                    user_id: {
                      offset: 2,
                      length: 23,
                      inner: "John <john@example.com>",
                    },
                  },
                },
              },
            },
          ],
        },
      });
      expect(container).toMatchSnapshot();
    });
  });
});

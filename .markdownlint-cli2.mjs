// Copyright (c) 2026 David Osipov

export default {
  config: {
    default: true,
    MD013: false,
    MD024: { siblings_only: true },
    MD040: true,
    MD046: { style: "fenced" },
    MD048: { style: "backtick" },
  },
  ignores: ["THIRD_PARTY_NOTICES.md"],
};

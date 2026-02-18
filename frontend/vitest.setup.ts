const createLocalStorageMock = () => {
  const store = new Map<string, string>();

  return {
    get length() {
      return store.size;
    },
    clear() {
      store.clear();
    },
    getItem(key: string) {
      return store.has(key) ? store.get(key) ?? null : null;
    },
    key(index: number) {
      if (index < 0 || index >= store.size) {
        return null;
      }
      return Array.from(store.keys())[index] ?? null;
    },
    removeItem(key: string) {
      store.delete(key);
    },
    setItem(key: string, value: string) {
      store.set(String(key), String(value));
    },
  };
};

const ensureLocalStorage = () => {
  const target = typeof window !== "undefined" ? window : globalThis;
  const current = target.localStorage as Storage | undefined;

  if (!current || typeof current.clear !== "function") {
    const mock = createLocalStorageMock();
    Object.defineProperty(target, "localStorage", {
      value: mock,
      configurable: true,
      enumerable: true,
      writable: false,
    });
    if (target !== globalThis) {
      Object.defineProperty(globalThis, "localStorage", {
        value: mock,
        configurable: true,
        enumerable: true,
        writable: false,
      });
    }
  }
};

ensureLocalStorage();

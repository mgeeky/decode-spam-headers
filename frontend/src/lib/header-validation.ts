export const MAX_HEADER_INPUT_BYTES = 1024 * 1024;

export const validateHeaderInput = (value: string): string | null => {
  if (value.length > MAX_HEADER_INPUT_BYTES) {
    return "Header input exceeds the 1 MB limit.";
  }

  if (value.trim().length === 0) {
    return "Header input cannot be empty.";
  }

  return null;
};

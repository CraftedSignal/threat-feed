// Parse comma-separated vendor input while preserving exact taxonomy titles
// that contain commas, such as "Amazon Web Services, Inc.".
export function vendorsFromInput(value, knownVendors = []) {
  const parts = (value || '').split(',').map((part) => part.trim());
  const known = [...new Set(knownVendors.filter(Boolean))]
    .sort((a, b) => b.split(',').length - a.split(',').length || b.length - a.length);
  const vendors = [];

  for (let index = 0; index < parts.length;) {
    let match;
    for (const vendor of known) {
      const vendorParts = vendor.split(',').map((part) => part.trim());
      const candidate = parts.slice(index, index + vendorParts.length);
      if (candidate.length === vendorParts.length && candidate.every((part, i) => part.toLocaleLowerCase() === vendorParts[i].toLocaleLowerCase())) {
        match = { value: vendor, length: vendorParts.length };
        break;
      }
    }

    if (match) {
      vendors.push(match.value);
      index += match.length;
    } else {
      if (parts[index]) vendors.push(parts[index]);
      index += 1;
    }
  }

  return vendors;
}

// Minimal IL2CPP global-metadata.dat parser / dumper (metadata version 31).
// Reconstructs the managed type/member surface and string literals without the
// native libil2cpp.so. Struct layouts mirror Il2CppDumper (Perfare) for v31.
const fs = require('fs');
const path = require('path');

const file = process.argv[2];
const outDir = process.argv[3] || '.';
const buf = fs.readFileSync(file);

const i32 = (o) => buf.readInt32LE(o);
const u32 = (o) => buf.readUInt32LE(o);
const u16 = (o) => buf.readUInt16LE(o);

// --- header: sequence of int32 fields included for version 31 ---
const H = {};
let p = 0;
const take = (name) => { H[name] = i32(p); p += 4; };
take('sanity'); take('version');
take('stringLiteralOffset'); take('stringLiteralSize');
take('stringLiteralDataOffset'); take('stringLiteralDataSize');
take('stringOffset'); take('stringSize');
take('eventsOffset'); take('eventsSize');
take('propertiesOffset'); take('propertiesSize');
take('methodsOffset'); take('methodsSize');
take('parameterDefaultValuesOffset'); take('parameterDefaultValuesSize');
take('fieldDefaultValuesOffset'); take('fieldDefaultValuesSize');
take('fieldAndParameterDefaultValueDataOffset'); take('fieldAndParameterDefaultValueDataSize');
take('fieldMarshaledSizesOffset'); take('fieldMarshaledSizesSize');
take('parametersOffset'); take('parametersSize');
take('fieldsOffset'); take('fieldsSize');
take('genericParametersOffset'); take('genericParametersSize');
take('genericParameterConstraintsOffset'); take('genericParameterConstraintsSize');
take('genericContainersOffset'); take('genericContainersSize');
take('nestedTypesOffset'); take('nestedTypesSize');
take('interfacesOffset'); take('interfacesSize');
take('vtableMethodsOffset'); take('vtableMethodsSize');
take('interfaceOffsetsOffset'); take('interfaceOffsetsSize');
take('typeDefinitionsOffset'); take('typeDefinitionsSize');
take('imagesOffset'); take('imagesSize');
take('assembliesOffset'); take('assembliesSize');
take('fieldRefsOffset'); take('fieldRefsSize');
take('referencedAssembliesOffset'); take('referencedAssembliesSize');
take('attributeDataOffset'); take('attributeDataSize');
take('attributeDataRangeOffset'); take('attributeDataRangeSize');
take('unresolvedVirtualCallParameterTypesOffset'); take('unresolvedVirtualCallParameterTypesSize');
take('unresolvedVirtualCallParameterRangesOffset'); take('unresolvedVirtualCallParameterRangesSize');
take('windowsRuntimeTypeNamesOffset'); take('windowsRuntimeTypeNamesSize');
take('windowsRuntimeStringsOffset'); take('windowsRuntimeStringsSize');
take('exportedTypeDefinitionsOffset'); take('exportedTypeDefinitionsSize');
const headerSize = p;

const magic = (H.sanity >>> 0).toString(16);
if (magic !== 'fab11baf') { console.error('Bad magic: 0x' + magic); process.exit(1); }
if (H.version !== 31) { console.error('Unexpected metadata version: ' + H.version); process.exit(1); }

// --- sizes ---
const SZ = {
  typeDefinition: 88,
  method: 36,
  field: 12,
  property: 20,
  parameter: 12,
  event: 24,
  image: 40,
  assembly: 68,
  stringLiteral: 8,
};
const counts = {
  types: H.typeDefinitionsSize / SZ.typeDefinition,
  methods: H.methodsSize / SZ.method,
  fields: H.fieldsSize / SZ.field,
  properties: H.propertiesSize / SZ.property,
  parameters: H.parametersSize / SZ.parameter,
  events: H.eventsSize / SZ.event,
  images: H.imagesSize / SZ.image,
  assemblies: H.assembliesSize / SZ.assembly,
  stringLiterals: H.stringLiteralSize / SZ.stringLiteral,
};

// --- readers ---
const readStr = (off) => {
  if (off < 0 || off >= H.stringSize) return null;
  const start = H.stringOffset + off;
  let end = start;
  while (end < buf.length && buf[end] !== 0) end++;
  return buf.toString('utf8', start, end);
};

const readTypes = () => {
  const a = [];
  for (let i = 0; i < counts.types; i++) {
    const o = H.typeDefinitionsOffset + i * SZ.typeDefinition;
    a.push({
      index: i,
      nameIndex: u32(o),
      namespaceIndex: u32(o + 4),
      byvalTypeIndex: i32(o + 8),
      declaringTypeIndex: i32(o + 12),
      parentIndex: i32(o + 16),
      elementTypeIndex: i32(o + 20),
      genericContainerIndex: i32(o + 24),
      flags: u32(o + 28),
      fieldStart: i32(o + 32),
      methodStart: i32(o + 36),
      eventStart: i32(o + 40),
      propertyStart: i32(o + 44),
      nestedTypesStart: i32(o + 48),
      interfacesStart: i32(o + 52),
      vtableStart: i32(o + 56),
      interfaceOffsetsStart: i32(o + 60),
      method_count: u16(o + 64),
      property_count: u16(o + 66),
      field_count: u16(o + 68),
      event_count: u16(o + 70),
      nested_type_count: u16(o + 72),
      vtable_count: u16(o + 74),
      interfaces_count: u16(o + 76),
      interface_offsets_count: u16(o + 78),
      bitfield: u32(o + 80),
      token: u32(o + 84),
    });
  }
  return a;
};
const readMethods = () => {
  const a = [];
  for (let i = 0; i < counts.methods; i++) {
    const o = H.methodsOffset + i * SZ.method;
    a.push({ index: i, nameIndex: u32(o), declaringType: i32(o + 4), returnType: i32(o + 8), returnParameterToken: i32(o + 12), parameterStart: i32(o + 16), genericContainerIndex: i32(o + 20), token: u32(o + 24), flags: u16(o + 28), iflags: u16(o + 30), slot: u16(o + 32), parameterCount: u16(o + 34) });
  }
  return a;
};
const readFields = () => {
  const a = [];
  for (let i = 0; i < counts.fields; i++) {
    const o = H.fieldsOffset + i * SZ.field;
    a.push({ index: i, nameIndex: u32(o), typeIndex: i32(o + 4), token: u32(o + 8) });
  }
  return a;
};
const readProperties = () => {
  const a = [];
  for (let i = 0; i < counts.properties; i++) {
    const o = H.propertiesOffset + i * SZ.property;
    a.push({ index: i, nameIndex: u32(o), get: i32(o + 4), set: i32(o + 8), attrs: u32(o + 12), token: u32(o + 16) });
  }
  return a;
};
const readParameters = () => {
  const a = [];
  for (let i = 0; i < counts.parameters; i++) {
    const o = H.parametersOffset + i * SZ.parameter;
    a.push({ index: i, nameIndex: u32(o), token: u32(o + 4), typeIndex: i32(o + 8) });
  }
  return a;
};
const readEvents = () => {
  const a = [];
  for (let i = 0; i < counts.events; i++) {
    const o = H.eventsOffset + i * SZ.event;
    a.push({ index: i, nameIndex: u32(o), typeIndex: i32(o + 4), add: i32(o + 8), remove: i32(o + 12), raise: i32(o + 16), token: u32(o + 20) });
  }
  return a;
};
const readImages = () => {
  const a = [];
  for (let i = 0; i < counts.images; i++) {
    const o = H.imagesOffset + i * SZ.image;
    a.push({ index: i, nameIndex: u32(o), assemblyIndex: i32(o + 4), typeStart: i32(o + 8), typeCount: u32(o + 12), exportedTypeStart: i32(o + 16), exportedTypeCount: u32(o + 20), entryPointIndex: i32(o + 24), token: u32(o + 28), customAttributeStart: i32(o + 32), customAttributeCount: u32(o + 36) });
  }
  return a;
};
const readStringLiterals = () => {
  const a = [];
  for (let i = 0; i < counts.stringLiterals; i++) {
    const o = H.stringLiteralOffset + i * SZ.stringLiteral;
    const length = u32(o);
    const dataIndex = i32(o + 4);
    if (dataIndex < 0 || dataIndex + length > H.stringLiteralDataSize) { a.push(null); continue; }
    const s = buf.toString('utf8', H.stringLiteralDataOffset + dataIndex, H.stringLiteralDataOffset + dataIndex + length);
    a.push(s);
  }
  return a;
};

const types = readTypes();
const methods = readMethods();
const fields = readFields();
const properties = readProperties();
const parameters = readParameters();
const events = readEvents();
const images = readImages();
const literals = readStringLiterals();

// --- sanity checks ---
const typeName = (t) => {
  const n = readStr(t.nameIndex) || '?';
  const ns = readStr(t.namespaceIndex) || '';
  return ns ? ns + '.' + n : n;
};
const third = types[2] ? typeName(types[2]) : '(none)';

// write a summary
const stats = [];
stats.push('file: ' + file);
stats.push('header bytes: ' + headerSize);
stats.push('version: ' + H.version + ' magic: 0x' + magic);
stats.push('string heap bytes: ' + H.stringSize);
stats.push('string literals: ' + counts.stringLiterals);
stats.push('types: ' + counts.types);
stats.push('methods: ' + counts.methods);
stats.push('fields: ' + counts.fields);
stats.push('properties: ' + counts.properties);
stats.push('parameters: ' + counts.parameters);
stats.push('events: ' + counts.events);
stats.push('images: ' + counts.images + ' assemblies: ' + counts.assemblies);
stats.push('types[0..3]: ' + [0, 1, 2, 3].map((i) => types[i] && typeName(types[i])).join(' | '));
stats.push('assemblies:');
for (const im of images) {
  const nm = readStr(im.nameIndex) || '?';
  stats.push('  [' + im.index + '] ' + nm + '  types=' + im.typeCount + ' typeStart=' + im.typeStart);
}
fs.writeFileSync(path.join(outDir, 'meta_stats.txt'), stats.join('\n'));

// full type/member dump
const lines = [];
const resName = (idx) => (idx >= 0 && idx < types.length) ? typeName(types[idx]) : '';
for (const im of images) {
  const nm = readStr(im.nameIndex) || '?';
  lines.push('// ===== ' + nm + ' (' + im.typeCount + ' types) =====');
  for (let ti = im.typeStart; ti < im.typeStart + im.typeCount && ti < types.length; ti++) {
    const t = types[ti];
    const kind = (t.bitfield & 1) ? 'struct' : ((t.bitfield >> 1) & 1) ? 'enum' : ((t.flags & 0x20) ? 'interface' : 'class');
    const parent = resName(t.parentIndex);
    lines.push(`${kind} ${typeName(t)}${parent ? ' : ' + parent : ''} {`);
    for (let fi = t.fieldStart; fi < t.fieldStart + t.field_count && fi < fields.length; fi++) {
      lines.push('    field ' + (readStr(fields[fi].nameIndex) || '?'));
    }
    for (let pi = t.propertyStart; pi < t.propertyStart + t.property_count && pi < properties.length; pi++) {
      lines.push('    prop  ' + (readStr(properties[pi].nameIndex) || '?'));
    }
    for (let mi = t.methodStart; mi < t.methodStart + t.method_count && mi < methods.length; mi++) {
      const m = methods[mi];
      const pn = [];
      for (let pi = m.parameterStart; pi < m.parameterStart + m.parameterCount && pi < parameters.length; pi++) pn.push(readStr(parameters[pi].nameIndex) || '?');
      lines.push('    method ' + (readStr(m.nameIndex) || '?') + '(' + pn.join(', ') + ')');
    }
    for (let ei = t.eventStart; ei < t.eventStart + t.event_count && ei < events.length; ei++) {
      lines.push('    event ' + (readStr(events[ei].nameIndex) || '?'));
    }
    lines.push('}');
  }
}
fs.writeFileSync(path.join(outDir, 'dump_metadata.txt'), lines.join('\n'));

// string literals
fs.writeFileSync(path.join(outDir, 'dump_stringliterals.txt'), literals.filter((x) => x !== null).join('\n'));

console.log(stats.slice(0, 12).join('\n'));
console.log('third type:', third);
console.log('wrote meta_stats.txt, dump_metadata.txt, dump_stringliterals.txt to', outDir);

# Image Notes

This directory contains notes about test images that exposed specific quirks
or implementation details during imago development.

Each file documents:
- What quirks the image exposed
- The specific values that revealed the behavior
- Links to relevant documentation

These notes help future developers understand why certain compatibility
behaviors exist and which images can be used to verify them.

## Index

| Image | Quirks Discovered |
|-------|-------------------|
| [qcow2-v2](qcow2-v2.md) | L1 table file length, block rounding, integer truncation |
| [cirros-qcow2](cirros-qcow2.md) | Decimal rounding, max(actual, calculated) file length |

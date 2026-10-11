/*
 * Copyright (c) 2026, OSTADIX contributors.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied the OpenJDK source).
 */

#ifndef SHARE_C1_C1_OCOREEXPORT_HPP
#define SHARE_C1_C1_OCOREEXPORT_HPP

class Compilation;

// Offline compiler-method export boundary. The sink is non-owning and must
// outlive the synchronous Compilation constructor. The implementation must
// lower the original HIR, retain Java semantics and provenance, and produce a
// verified NativeModule body. PrintIR output and bytecode wrappers do not count.
//
// This interface is deliberately abstract. No semantic exporter is implemented
// by the hook, and no caller can claim successful lowering without supplying one.
class OcoreC1ExportSink {
 public:
  virtual ~OcoreC1ExportSink() {}

  // nullptr means successful module emission. A failure message must have
  // compilation-lifetime storage and propagates through the existing bailout.
  virtual const char* export_method(Compilation* compilation) = 0;
};

#endif // SHARE_C1_C1_OCOREEXPORT_HPP

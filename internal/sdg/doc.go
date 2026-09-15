// SPDX-License-Identifier: GPL-3.0-or-later

// Package sdg speaks SecureDeviceGrid: identity keys, the connection to a grid
// server, pairing, and peer connections both relayed and direct.
//
// This package is a port to Go of the opensdg C library,
// https://github.com/Sonic-Amiga/opensdg, Copyright (C) Pavel Fedin, which is
// licensed under the GNU General Public License version 3. It is therefore a
// derivative work, and is the reason this whole program carries that licence;
// see the LICENSE and NOTICE files at the repository root for the terms and for
// what was changed. No opensdg source is included here.
//
// The handshake it implements is a variant of CurveCP in the shape CurveZMQ
// gives it: HELO, COOK, VOCH, REDY and MESG correspond to that protocol's
// HELLO, WELCOME, INITIATE, READY and MESSAGE. The direct local connection is
// not part of opensdg and was worked out against a real frame.
package sdg

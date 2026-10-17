// Modified by 새올정보기술 for OV-Works (2026). Changes against oVirt Engine 4.5.6: docs/ovworks-source-change-statement.md
package org.ovirt.engine.core.utils;

import org.apache.commons.codec.binary.Base64;
import org.ovirt.engine.core.uutils.crypto.ApprovedRandom;

public final class Ticketing {
    public static String generateOTP() {
        // libvirt limits to 8 chars length password
        byte[] arrRandom = new byte[6];
        ApprovedRandom.nextBytes(arrRandom);
        // encode password into Base64 text:
        return new Base64(0).encodeToString(arrRandom);
    }
}

/* jcifs smb client library in Java
 * Copyright (C) 2004  "Michael B. Allen" <jcifs at samba dot org>
 *                   "Eric Glass" <jcifs at samba dot org>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package jcifs.spnego;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.util.Enumeration;

import jcifs.spnego.asn1.ASN1EncodableVector;
import jcifs.spnego.asn1.ASN1OctetString;
import jcifs.spnego.asn1.ASN1Sequence;
import jcifs.spnego.asn1.ASN1TaggedObject;
import jcifs.spnego.asn1.DERBitString;
import jcifs.spnego.asn1.DERInputStream;
import jcifs.spnego.asn1.DERObject;
import jcifs.spnego.asn1.DERObjectIdentifier;
import jcifs.spnego.asn1.DEROctetString;
import jcifs.spnego.asn1.DEROutputStream;
import jcifs.spnego.asn1.DERSequence;
import jcifs.spnego.asn1.DERTaggedObject;
import jcifs.spnego.asn1.DERTags;
import jcifs.spnego.asn1.DERUnknownTag;

public class NegTokenInit extends SpnegoToken {

    public static final int DELEGATION = 0x40;

    public static final int MUTUAL_AUTHENTICATION = 0x20;

    public static final int REPLAY_DETECTION = 0x10;

    public static final int SEQUENCE_CHECKING = 0x08;

    public static final int ANONYMITY = 0x04;

    public static final int CONFIDENTIALITY = 0x02;

    public static final int INTEGRITY = 0x01;

    private String[] mechanisms;

    private int contextFlags;

    public NegTokenInit() { }

    public NegTokenInit(String[] mechanisms, int contextFlags,
            byte[] mechanismToken, byte[] mechanismListMIC) {
        setMechanisms(mechanisms);
        setContextFlags(contextFlags);
        setMechanismToken(mechanismToken);
        setMechanismListMIC(mechanismListMIC);
    }

    public NegTokenInit(byte[] token) throws IOException {
        parse(token);
    }

    public int getContextFlags() {
        return contextFlags;
    }

    public void setContextFlags(int contextFlags) {
        this.contextFlags = contextFlags;
    }

    public boolean getContextFlag(int flag) {
        return (getContextFlags() & flag) == flag;
    }

    public void setContextFlag(int flag, boolean value) {
        setContextFlags(value ? (getContextFlags() | flag) :
                (getContextFlags() & (0xffffffff ^ flag)));
    }

    public String[] getMechanisms() {
        return mechanisms;
    }

    public void setMechanisms(String[] mechanisms) {
        this.mechanisms = mechanisms;
    }

    public byte[] toByteArray() {
        try {
            ByteArrayOutputStream collector = new ByteArrayOutputStream();
            DEROutputStream der = new DEROutputStream(collector);
            der.writeObject(new DERObjectIdentifier(
                    SpnegoConstants.SPNEGO_MECHANISM));
            ASN1EncodableVector fields = new ASN1EncodableVector();
            String[] mechanisms = getMechanisms();
            if (mechanisms != null) {
                ASN1EncodableVector vector = new ASN1EncodableVector();
                for (int i = 0; i < mechanisms.length; i++) {
                    vector.add(new DERObjectIdentifier(mechanisms[i]));
                }
                fields.add(new DERTaggedObject(true, 0,
                        new DERSequence(vector)));
            }
            int contextFlags = getContextFlags();
            if (contextFlags != 0) {
                fields.add(new DERTaggedObject(true, 1,
                        new DERBitString(contextFlags)));
            }
            byte[] mechanismToken = getMechanismToken();
            if (mechanismToken != null) {
                fields.add(new DERTaggedObject(true, 2,
                        new DEROctetString(mechanismToken)));
            }
            byte[] mechanismListMIC = getMechanismListMIC();
            if (mechanismListMIC != null) {
                fields.add(new DERTaggedObject(true, 3,
                        new DEROctetString(mechanismListMIC)));
            }
            der.writeObject(new DERTaggedObject(true, 0,
                        new DERSequence(fields)));
            DERObject token = new DERUnknownTag(DERTags.CONSTRUCTED |
                    DERTags.APPLICATION, collector.toByteArray());
            der = new DEROutputStream(collector = new ByteArrayOutputStream());
            der.writeObject(token);
            return collector.toByteArray();
        } catch (IOException ex) {
            throw new IllegalStateException(ex.getMessage());
        }
    }

    protected void parse(byte[] token) throws IOException {
        ByteArrayInputStream tokenStream = new ByteArrayInputStream(token);
        DERInputStream der = new DERInputStream(tokenStream);
        DERUnknownTag constructed = (DERUnknownTag) der.readObject();
        if (constructed.getTag() !=
                (DERTags.CONSTRUCTED | DERTags.APPLICATION)) {
            throw new IOException("Malformed NegTokenInit.");
        }
        tokenStream = new ByteArrayInputStream(constructed.getData());
        der = new DERInputStream(tokenStream);
        DERObjectIdentifier spnego = (DERObjectIdentifier) der.readObject();
        ASN1TaggedObject tagged = (ASN1TaggedObject) der.readObject();
        ASN1Sequence sequence = ASN1Sequence.getInstance(tagged, true);
        Enumeration fields = sequence.getObjects();
        while (fields.hasMoreElements()) {
            tagged = (ASN1TaggedObject) fields.nextElement();
            switch (tagged.getTagNo()) {
            case 0:
                sequence = ASN1Sequence.getInstance(tagged, true);
                String[] mechanisms = new String[sequence.size()];
                for (int i = mechanisms.length - 1; i >= 0; i--) {
                    DERObjectIdentifier mechanism = (DERObjectIdentifier)
                            sequence.getObjectAt(i);
                    mechanisms[i] = mechanism.getId();
                }
                setMechanisms(mechanisms);
                break;
            case 1:
                DERBitString contextFlags = DERBitString.getInstance(tagged,
                        true);
                setContextFlags(contextFlags.getBytes()[0] & 0xff);
                break;
            case 2:
                ASN1OctetString mechanismToken =
                        ASN1OctetString.getInstance(tagged, true);
                setMechanismToken(mechanismToken.getOctets());
                break;
            case 3:
                ASN1OctetString mechanismListMIC =
                        ASN1OctetString.getInstance(tagged, true);
                setMechanismListMIC(mechanismListMIC.getOctets());
                break;
            default:
                throw new IOException("Malformed token field.");
            }
        }
    }

}

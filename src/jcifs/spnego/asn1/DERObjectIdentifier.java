/* Copyright (c) 2000 The Legion Of The Bouncy Castle
 * (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package jcifs.spnego.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class DERObjectIdentifier
    extends DERObject
{
    String      identifier;

    /**
     * return an OID from the passed in object
     *
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static DERObjectIdentifier getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERObjectIdentifier)
        {
            return (DERObjectIdentifier)obj;
        }

        if (obj instanceof ASN1OctetString)
        {
            return new DERObjectIdentifier(((ASN1OctetString)obj).getOctets());
        }

        if (obj instanceof ASN1TaggedObject)
        {
            return getInstance(((ASN1TaggedObject)obj).getObject());
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an Object Identifier from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     */
    public static DERObjectIdentifier getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(obj.getObject());
    }
    

    DERObjectIdentifier(
        byte[]  bytes)
    {
        StringBuffer    objId = new StringBuffer();
        int             value = 0;
        boolean         first = true;

        for (int i = 0; i != bytes.length; i++)
        {
            int b = bytes[i] & 0xff;

            value = value * 128 + (b & 0x7f);
            if ((b & 0x80) == 0)             // end of number reached
            {
                if (first)
                {
                    switch (value / 40)
                    {
                    case 0:
                        objId.append('0');
                        break;
                    case 1:
                        objId.append('1');
                        value -= 40;
                        break;
                    default:
                        objId.append('2');
                        value -= 80;
                    }
                    first = false;
                }

                objId.append('.');
                objId.append(Integer.toString(value));
                value = 0;
            }
        }

        this.identifier = objId.toString();
    }

    public DERObjectIdentifier(
        String  identifier)
    {
        this.identifier = identifier;
    }

    public String getId()
    {
        return identifier;
    }

    private void writeField(
        OutputStream    out,
        int             fieldValue)
        throws IOException
    {
        if (fieldValue >= (1 << 7))
        {
            if (fieldValue >= (1 << 14))
            {
                if (fieldValue >= (1 << 21))
                {
                    if (fieldValue >= (1 << 28))
                    {
                        out.write((fieldValue >> 28) | 0x80);
                    }
                    out.write((fieldValue >> 21) | 0x80);
                }
                out.write((fieldValue >> 14) | 0x80);
            }
            out.write((fieldValue >> 7) | 0x80);
        }
        out.write(fieldValue & 0x7f);
    }

    void encode(
        DEROutputStream out)
        throws IOException
    {
        OIDTokenizer            tok = new OIDTokenizer(identifier);
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        DEROutputStream         dOut = new DEROutputStream(bOut);

        writeField(bOut, 
                    Integer.parseInt(tok.nextToken()) * 40
                    + Integer.parseInt(tok.nextToken()));

        while (tok.hasMoreTokens())
        {
            writeField(bOut, Integer.parseInt(tok.nextToken()));
        }

        dOut.close();

        byte[]  bytes = bOut.toByteArray();

        out.writeEncoded(OBJECT_IDENTIFIER, bytes);
    }

    public int hashCode()
    {
        return identifier.hashCode();
    }

    public boolean equals(
        Object  o)
    {
        if ((o == null) || !(o instanceof DERObjectIdentifier))
        {
            return false;
        }

        return identifier.equals(((DERObjectIdentifier)o).identifier);
    }
}

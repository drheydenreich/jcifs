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

import java.io.IOException;
import java.util.Enumeration;

/**
 * BER TaggedObject - in ASN.1 nottation this is any object proceeded by
 * a [n] where n is some number - these are assume to follow the construction
 * rules (as with sequences).
 */
public class BERTaggedObject
    extends DERTaggedObject
{
    /**
     * @param tagNo the tag number for this object.
     * @param obj the tagged object.
     */
    public BERTaggedObject(
        int             tagNo,
        DEREncodable    obj)
    {
        super(tagNo, obj);
    }

    /**
     * @param explicit true if an explicitly tagged object.
     * @param tagNo the tag number for this object.
     * @param obj the tagged object.
     */
    public BERTaggedObject(
        boolean         explicit,
        int             tagNo,
        DEREncodable    obj)
    {
        super(explicit, tagNo, obj);
    }

    /**
     * create an implicitly tagged object that contains a zero
     * length sequence.
     */
    public BERTaggedObject(
        int             tagNo)
    {
        super(false, tagNo, new BERConstructedSequence());
    }

    void encode(
        DEROutputStream  out)
        throws IOException
    {
        if (out instanceof ASN1OutputStream || out instanceof BEROutputStream)
        {
            out.write(CONSTRUCTED | TAGGED | tagNo);
            out.write(0x80);

            if (!empty)
            {
                if (!explicit)
                {
                    if (obj instanceof ASN1OctetString)
                    {
                        Enumeration  e;

                        if (obj instanceof BERConstructedOctetString)
                        {
                            e = ((BERConstructedOctetString)obj).getObjects();
                        }
                        else
                        {
                            ASN1OctetString             octs = (ASN1OctetString)obj;
                            BERConstructedOctetString   berO = new BERConstructedOctetString(octs.getOctets());

                            e = berO.getObjects();
                        }

                        while (e.hasMoreElements())
                        {
                            out.writeObject(e.nextElement());
                        }
                    }
                    else if (obj instanceof ASN1Sequence)
                    {
                        Enumeration  e = ((ASN1Sequence)obj).getObjects();

                        while (e.hasMoreElements())
                        {
                            out.writeObject(e.nextElement());
                        }
                    }
                    else if (obj instanceof ASN1Set)
                    {
                        Enumeration  e = ((ASN1Set)obj).getObjects();

                        while (e.hasMoreElements())
                        {
                            out.writeObject(e.nextElement());
                        }
                    }
                    else
                    {
                        throw new RuntimeException("not implemented: " + obj.getClass().getName());
                    }
                }
                else
                {
                    out.writeObject(obj);
                }
            }

            out.write(0x00);
            out.write(0x00);
        }
        else
        {
            super.encode(out);
        }
    }
}

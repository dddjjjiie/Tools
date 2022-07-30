package org.dddjjj.cryptography.vc.cvc;

import org.dddjjj.cryptography.vc.cdh.CDHPP;
import org.dddjjj.cryptography.vc.SerializableElement;

public class CVCPP extends CDHPP {
    public CVCPP(SerializableElement g, SerializableElement[] hi, SerializableElement[][] hij) {
        super(g, hi, hij);
    }
}

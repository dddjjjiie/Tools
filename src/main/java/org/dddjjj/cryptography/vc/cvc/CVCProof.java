package org.dddjjj.cryptography.vc.cvc;

import it.unisa.dia.gas.jpbc.Element;

public class CVCProof {
    Element proof;

    public CVCProof(Element proof){
        this.proof = proof;
    }

    public Element getProof(){
        return proof;
    }
}

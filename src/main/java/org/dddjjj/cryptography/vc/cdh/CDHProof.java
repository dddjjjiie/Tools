package org.dddjjj.cryptography.vc.cdh;


import it.unisa.dia.gas.jpbc.Element;

public class CDHProof {
    Element proof;

    public CDHProof(Element proof){
        this.proof = proof;
    }

    public Element getProof(){
        return proof;
    }
}

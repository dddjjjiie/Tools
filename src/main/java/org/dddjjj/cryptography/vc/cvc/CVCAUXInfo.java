package org.dddjjj.cryptography.vc.cvc;

import it.unisa.dia.gas.jpbc.Element;
import org.dddjjj.cryptography.vc.cdh.CDHAUXInfo;
import org.dddjjj.cryptography.vc.cdh.CDHVC;

public class CVCAUXInfo<M> extends CDHAUXInfo<M> {
    Element r;

    public CVCAUXInfo(){

    }

    public CVCAUXInfo(M[] vector, Element r){
        this.vector = vector;
        this.r = r;
    }

    public void setR(Element r){
        this.r = r;
    }

    public Element getR(){
        return r;
    }
}

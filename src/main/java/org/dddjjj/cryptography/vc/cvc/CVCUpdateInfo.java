package org.dddjjj.cryptography.vc.cvc;


import it.unisa.dia.gas.jpbc.Element;

public class CVCUpdateInfo {
    int pos;
    Element u;

    public CVCUpdateInfo(int i, Element u){
        pos = i;
        this.u = u;
    }
}

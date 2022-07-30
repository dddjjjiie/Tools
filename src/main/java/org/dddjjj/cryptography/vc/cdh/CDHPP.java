package org.dddjjj.cryptography.vc.cdh;

import it.unisa.dia.gas.jpbc.Element;

public class CDHPP {
    SerializableElement g;
    int q;
    SerializableElement[] hi;
    SerializableElement[][] hij;

    public Element getHi(int i){
        return hi[i].getElement();
    }

    public Element getHij(int i, int j){
        return hij[i][j].getElement();
    }

    public CDHPP(SerializableElement g, SerializableElement[] hi, SerializableElement[][] hij){
        this.g = g;
        this.q = hi.length;
        this.hi = hi;
        this.hij = hij;
    }

}

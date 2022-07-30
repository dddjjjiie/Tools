package org.dddjjj.cryptography.vc.cdh;

import it.unisa.dia.gas.jpbc.Element;
import org.dddjjj.cryptography.vc.SerializableElement;

public class CDHPP {
    public SerializableElement g;
    public int q;
    public SerializableElement[] hi;
    public SerializableElement[][] hij;

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

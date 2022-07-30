package org.dddjjj.cryptography.vc.cvc;

import it.unisa.dia.gas.jpbc.Element;

public class Td {
    private Element[] zs;

    public Td(Element[] zs){
        this.zs = zs;
    }

    public Element[] getTd(){
        return zs;
    }

    public Element getZ(int i){
        return zs[i];
    }
}

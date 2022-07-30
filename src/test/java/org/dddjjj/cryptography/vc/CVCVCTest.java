package org.dddjjj.cryptography.vc;

import it.unisa.dia.gas.jpbc.Element;
import org.dddjjj.cryptography.vc.cvc.*;
import org.junit.Test;

public class CVCVCTest {

    @Test
    public void test(){
        int k = 1, q = 5;
        String[] vector = new String[]{"a", "b", "c", "d", "e"};
        ChameleonVC vc = new ChameleonVC();
        CVCPP pp = vc.keyGen(k, q);
        CVCAUXInfo aux = new CVCAUXInfo();
        Element c = vc.com(pp, vector, aux);

        //proof of existence
        CVCProof proof = vc.open(pp, "a", 0, aux);
        boolean ver = vc.ver(pp, c, "a", 0, proof);
        System.out.println(ver);

        aux = vc.col(c, 0, "a", "f", aux);
        ver = vc.ver(pp, c, "f", 0, proof);
        System.out.println(ver);

        proof = vc.open(pp, "f", 0, aux);
        ver = vc.ver(pp, c, "f", 0, proof);
        System.out.println(ver);

        CVCUpdateInfo updateInfo = vc.update(pp, c.duplicate(), "f", "g", 0);
        proof = vc.proofUpdate(pp, c, proof, "g", 0, updateInfo);
        ver = vc.ver(pp, c, "g", 0, proof);
        System.out.println(ver);
    }

    @Test
    public void testNode(){
        int k = 1, q = 5;
        String[] vector = new String[]{"0", "0", "0", "0", "0"};
        ChameleonVC vc = new ChameleonVC();
        CVCPP pp = vc.keyGen(k, q);
        CVCAUXInfo initAux1 = new CVCAUXInfo();
        Element c1 = vc.com(pp, vector, initAux1);
        CVCAUXInfo dataAux1 = vc.col(c1, 0, "0", "a", initAux1);

        CVCAUXInfo initAux2 = new CVCAUXInfo();
        Element c2 = vc.com(pp, vector, initAux2);
        CVCAUXInfo dataAux2 = vc.col(c2, 0, "0", "b", initAux1);

        CVCAUXInfo parAux = new CVCAUXInfo();
        Element parC = vc.com(pp, vector, parAux);
        CVCAUXInfo parInitAux = new CVCAUXInfo(parAux.vector, parAux.getR());
        parAux = vc.col(parC, 1, "0", new String(c2.toBytes()), parAux);

        CVCAUXInfo childAux = new CVCAUXInfo();
        CVCProof childProof = vc.open(pp, new String(c2.toBytes()), 1, parInitAux);
        System.out.println(vc.ver(pp, parC, new String(c2.toBytes()), 1, childProof));
    }
}

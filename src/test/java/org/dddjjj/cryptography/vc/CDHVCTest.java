package org.dddjjj.cryptography.vc;

import it.unisa.dia.gas.jpbc.Element;
import org.dddjjj.cryptography.vc.cdh.*;
import org.junit.Test;

public class CDHVCTest {
    @Test
    public void test(){
        CDHVC vc = new CDHVC();
        int k = 1, q = 5;
        CDHPP pp = vc.keyGen(k, q);
        String[] vector = new String[] {"a", "b", "c", "d", "e"};
        CDHAUXInfo<String> aux = new CDHAUXInfo<>();
        Element c = vc.com(pp, vector, aux);

        //proof of existence
        CDHProof proof = vc.open(pp, "a", 0, aux);
        boolean ver = vc.ver(pp, c, vector[0], 0, proof);
        System.out.println(ver);

        //proof of non-existence
        proof = vc.open(pp, "f", 0, aux);
        ver = vc.ver(pp, c, "f", 0, proof);
        System.out.println(ver);

        //update
        CDHUpdateInfo u = vc.update(pp, c.duplicate(), "a", "f", 0);
        proof = vc.proofUpdate(pp, c, proof, "f", 0, u);
        ver = vc.ver(pp, c, "f", 0, proof);
        System.out.println(ver);
    }
}

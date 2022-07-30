package org.dddjjj.cryptography.vc.cdh;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.dddjjj.cryptography.vc.VC;

public class CDHVC implements VC<String, Element, CDHAUXInfo<String>, CDHPP, CDHProof, CDHUpdateInfo<String>> {

    Pairing pairing = PairingFactory.getPairing("params/curves/a.properties");
    Element[] zs;
    @Override
    public CDHPP keyGen(int k, int q) {
        Element g = pairing.getG1().newRandomElement();
        zs = new Element[q];
        SerializableElement[] hi = new SerializableElement[q];
        SerializableElement[][] hij = new SerializableElement[q][q];
        for(int i=0; i<q; i++){
            zs[i] = pairing.getZr().newRandomElement();
            hi[i] = new SerializableElement(g.duplicate().powZn(zs[i]));
        }
        for(int i=0; i<q; i++){
            for(int j=0; j<q; j++){
                if(j == i) continue;
                hij[i][j] = new SerializableElement(hi[i].getElement().duplicate().powZn(zs[j])); //only compute half,hij = hji
            }
        }
        return new CDHPP(new SerializableElement(g), hi, hij);
    }

    @Override
    public Element com(CDHPP pp, String[] vector, CDHAUXInfo<String> aux) {
        Element c = pairing.getG1().newOneElement();
        if(vector.length != pp.q){
            System.err.print("vector length:" + vector.length + " q:" + pp.q);
            return null;
        }
        for(int i=0; i<vector.length; i++){
            Element m = pairing.getZr().newElementFromHash(vector[i].getBytes(), 0, vector[i].getBytes().length);
            c = c.mul(pp.getHi(i).duplicate().powZn(m));
        }
        aux.setVector(vector);
        return c;
    }

    @Override
    public CDHProof open(CDHPP pp, String msg, int i, CDHAUXInfo<String> aux) {
        Element proof = pairing.getG1().newOneElement();
        for(int j=0; j<pp.q; j++){
            if(j == i) continue;
            proof.mul(pp.getHi(j).duplicate().powZn(pairing.getZr().newElementFromHash(aux.getMsg(j).getBytes(), 0, aux.getMsg(j).getBytes().length)));
        }
        proof.powZn(zs[i]);
        return new CDHProof(proof);
    }

    @Override
    public boolean ver(CDHPP pp, Element c, String msg, int i, CDHProof cdhProof) {
        Element left = pairing.pairing(c.duplicate().div(pp.getHi(i).duplicate().powZn(pairing.getZr().newElementFromHash(msg.getBytes(), 0, msg.getBytes().length))), pp.getHi(i));
        Element right = pairing.pairing(cdhProof.getProof(), pp.g.getElement());
        return left.equals(right);
    }

    @Override
    public CDHUpdateInfo<String> update(CDHPP pp, Element c, String oldMsg, String msg, int i) {
        Element m1 = pairing.getZr().newElementFromHash(oldMsg.getBytes(), 0, oldMsg.getBytes().length);
        Element m2 = pairing.getZr().newElementFromHash(msg.getBytes(), 0, msg.getBytes().length);
        c.mul(pp.getHi(i).duplicate().powZn(m2.sub(m1)));
        return new CDHUpdateInfo<String>(oldMsg, msg, i);
    }

    @Override
    public CDHProof proofUpdate(CDHPP pp, Element c, CDHProof cdhProof, String msg, int i, CDHUpdateInfo<String> u) {
        Element m1 = pairing.getZr().newElementFromHash(u.oldMsg.getBytes(), 0, u.oldMsg.getBytes().length);
        Element m2 = pairing.getZr().newElementFromHash(msg.getBytes(), 0, msg.getBytes().length);
        c.mul(pp.getHi(i).duplicate().powZn(m2.sub(m1)));
        if(i != u.pos){
            cdhProof.proof.mul(pp.getHij(i, u.pos).duplicate().powZn(m2.sub(m1)));
        }
        return cdhProof;
    }
}

package org.dddjjj.cryptography.vc.cvc;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.dddjjj.cryptography.vc.SerializableElement;
import org.dddjjj.cryptography.vc.VC;
import org.dddjjj.cryptography.vc.cdh.CDHPP;
import org.dddjjj.cryptography.vc.cdh.CDHProof;
import org.dddjjj.cryptography.vc.cdh.CDHUpdateInfo;

public class ChameleonVC implements VC<String, Element, CVCAUXInfo<String>, CVCPP, CVCProof, CVCUpdateInfo>  {

    Pairing pairing = PairingFactory.getPairing("params/curves/a.properties");
    Element[] zs;

    @Override
    public CVCPP keyGen(int k, int q) {
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
        return new CVCPP(new SerializableElement(g), hi, hij);
    }

    @Override
    public Element com(CVCPP pp, String[] vector, CVCAUXInfo<String> aux) {
        Element c = pairing.getG1().newOneElement();
        Element r = pairing.getZr().newRandomElement();
        if(vector.length != pp.q){
            System.err.print("vector length:" + vector.length + " q:" + pp.q);
            return null;
        }
        for(int i=0; i<vector.length; i++){
            Element m = pairing.getZr().newElementFromHash(vector[i].getBytes(), 0, vector[i].getBytes().length);
            c = c.mul(pp.getHi(i).duplicate().powZn(m));
        }
        c.mul(pp.g.getElement().duplicate().powZn(r));
        aux.setVector(vector);
        aux.setR(r);
        return c;
    }

    @Override
    public CVCProof open(CVCPP pp, String msg, int i, CVCAUXInfo<String> aux) {
        Element proof = pairing.getG1().newOneElement();
        for(int j=0; j<pp.q; j++){
            if(j == i) continue;
            proof.mul(pp.getHi(j).duplicate().powZn(pairing.getZr().newElementFromHash(aux.getMsg(j).getBytes(), 0, aux.getMsg(j).getBytes().length)));
        }
        proof.powZn(zs[i]);
        proof.mul(pp.getHi(i).duplicate().powZn(aux.getR()));
        return new CVCProof(proof);
    }

    @Override
    public boolean ver(CVCPP pp, Element c, String msg, int i, CVCProof proof) {
        Element left = pairing.pairing(c.duplicate().div(pp.getHi(i).duplicate().powZn(pairing.getZr().newElementFromHash(msg.getBytes(), 0, msg.getBytes().length))), pp.getHi(i));
        Element right = pairing.pairing(proof.getProof(), pp.g.getElement());
        return left.equals(right);
    }

    public CVCAUXInfo<String> col(Element c, int i, String oldMsg, String msg, CVCAUXInfo<String> aux){
        Element m1 = pairing.getZr().newElementFromHash(oldMsg.getBytes(), 0, oldMsg.getBytes().length);
        Element m2 = pairing.getZr().newElementFromHash(msg.getBytes(), 0, msg.getBytes().length);
        aux.setR(aux.getR().add(zs[i].duplicate().mul(m1.sub(m2))));
        aux.setMsg(i, msg);
        return aux;
    }

    @Override
    public CVCUpdateInfo update(CVCPP pp, Element c, String oldMsg, String msg, int i) {
        Element m1 = pairing.getZr().newElementFromHash(oldMsg.getBytes(), 0, oldMsg.getBytes().length);
        Element m2 = pairing.getZr().newElementFromHash(msg.getBytes(), 0, msg.getBytes().length);
        c.mul(pp.getHi(i).duplicate().powZn(m2.sub(m1)));
        return new CVCUpdateInfo(i, m2);
    }

    @Override
    public CVCProof proofUpdate(CVCPP pp, Element c, CVCProof proof, String msg, int i, CVCUpdateInfo updateInfo) {
        c.mul(pp.getHi(i).duplicate().powZn(updateInfo.u));
        if(i != updateInfo.pos){
            proof.proof.mul(pp.getHij(i, updateInfo.pos).duplicate().powZn(updateInfo.u));
        }
        return proof;
    }
}

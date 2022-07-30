package org.dddjjj.cryptography.vc;

public interface VC<M, C, AUXInfo, PP, Proof, UpdateInfo> {

    public PP keyGen(int k, int q);

    public C com(PP pp, M[] vector, AUXInfo aux);

    public Proof open(PP pp, M msg, int i, AUXInfo aux);

    public boolean ver(PP pp, C c, M msg, int i, Proof proof);

    public UpdateInfo update(PP pp, C c, M msg1, M msg2, int i);

    public Proof proofUpdate(PP pp, C c, Proof proof, M msg, int i, UpdateInfo u);
}

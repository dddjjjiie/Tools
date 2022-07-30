package org.dddjjj.cryptography.vc.cdh;

public class CDHUpdateInfo<M> {
    M oldMsg, msg;
    int pos;

    public CDHUpdateInfo(M oldMsg, M msg, int pos){
        this.oldMsg = oldMsg;
        this.msg = msg;
        this.pos = pos;
    }
}

package org.dddjjj.cryptography.vc.cdh;

public class CDHAUXInfo<M> {
    public M[] vector;

    public CDHAUXInfo(){

    }

    public CDHAUXInfo(M[] vector){
        this.vector = vector;
    }

    public M getMsg(int i){
        return vector[i];
    }

    public void setMsg(int i, M msg){
        vector[i] = msg;
    }

    public void setVector(M[] vector){
        this.vector = vector;
    }
}

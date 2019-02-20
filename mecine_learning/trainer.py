import numpy as np
import torch.nn as nn
import torch.nn.functional as F
import torch
import sys 
import embeder
import RNN_model


h_dim = 10
h_layer = 2
x_f = 10
out_h = 4
zero_value = 256
b_size = 82

def train(input_X, output_X, lengths, h_state, model, model_optim):
    output_X = output_X 
    model_optim.zero_grad()
    out,_ = model(input_X, lengths, h_state)
    nllloss = nn.NLLLoss()
    loss = nllloss(out, output_X)
    loss.backward()
    model_optim.step()
    return loss


def train_Iter(datas, h_state, model, model_optim, per_iter, T_round):
    for i in range(T_round):
        loss = train(datas[0], datas[1], datas[2], h_state, model, model_optim)
        if(i % per_iter == 0):
            print("iters: ", i, ",loss is ", loss)

def test(path):
    baseone = embeder.base_process(zero_value)
    baseone.init_data(path)
    embedding = nn.Embedding(len(baseone.voc), x_f)
    Data = baseone.inputs2T(baseone.datas)
    state = torch.randn(h_layer, b_size, h_dim)
    rnn = RNN_model.textclass(embedding, x_f, h_dim, h_layer, len(baseone.cate))
    optimer = torch.optim.SGD(rnn.parameters(), lr=0.1, momentum=0.9)
    train_Iter(Data, state, rnn, optimer, 10, 1000)

test('/home/wxw/one_shot')

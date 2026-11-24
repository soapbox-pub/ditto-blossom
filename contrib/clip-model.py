#!/usr/bin/env python3
"""Export the image encoder ditto-blossom scans with: OpenAI's CLIP ViT-B/32
(MIT), its image tower and projection, 224x224 in, 512 numbers out, fp32.

    python3 -m venv venv
    venv/bin/pip install --index-url https://download.pytorch.org/whl/cpu torch
    venv/bin/pip install transformers onnx onnxruntime
    venv/bin/python contrib/clip-model.py /var/lib/ditto-blossom/clip-b32.onnx

Then train the head over it on your own labels (`ditto-blossom train`).

--int8 quantizes it, ~1.47x quicker on one core, all but eight layers. Plain
int8 took its accuracy from AUC 0.993 to 0.88: the first MLP layer of
blocks 1-6, fed by CLIP's activation outliers, moved embeddings 40-64% each
alone, and v_proj of blocks 6 and 11 a little; those stay fp32. Tested on
3,449 labels, it caught and wrongly blocked as many as fp32 at a 99% catch,
but not the same ones: 3 of its 14 misses were images fp32 caught (and the
reverse). Retrain the head over it.

Smaller encoders (TinyCLIP, B/32 at 160 px) were faster but blocked 20-30%
more clean images to catch as much.
"""
import os
import sys

import numpy as np
import onnx
import onnxruntime as ort
import torch
from transformers import CLIPVisionModelWithProjection

out = next(a for a in sys.argv[1:] if not a.startswith("--"))
int8 = "--int8" in sys.argv
m = CLIPVisionModelWithProjection.from_pretrained("openai/clip-vit-base-patch32").eval()


class Tower(torch.nn.Module):
    def __init__(self, m):
        super().__init__()
        self.m = m

    def forward(self, x):
        return self.m(pixel_values=x).image_embeds


x = torch.randn(1, 3, 224, 224)
with torch.no_grad():
    torch.onnx.export(Tower(m), x, out, input_names=["pixel_values"], output_names=["image_embeds"],
                      opset_version=17, dynamo=False)
    want = m(pixel_values=x).image_embeds.numpy()
onnx.save(onnx.load(out), out)  # one file, weights inline
got = ort.InferenceSession(out).run(None, {"pixel_values": x.numpy()})[0]
if np.abs(got - want).max() > 1e-3:
    sys.exit(f"the export differs from the model by {np.abs(got - want).max()}")
if int8:
    from onnxruntime.quantization import QuantType, quantize_dynamic
    layer = "/m/vision_model/encoder/layers."
    keep = [f"{layer}{i}/mlp/fc1/MatMul" for i in range(1, 7)] + [f"{layer}{i}/self_attn/v_proj/MatMul" for i in (6, 11)]
    names = {n.name for n in onnx.load(out).graph.node}
    missing = [k for k in keep if k not in names]
    if missing:
        sys.exit(f"not the expected export; no {missing}")
    fp32 = out + ".fp32"
    os.replace(out, fp32)
    quantize_dynamic(fp32, out, weight_type=QuantType.QInt8, per_channel=True,
                     op_types_to_quantize=["MatMul", "Gemm"], nodes_to_exclude=keep)
    os.remove(fp32)
    got = ort.InferenceSession(out).run(None, {"pixel_values": x.numpy()})[0]
    cos = float((got * want).sum() / np.linalg.norm(got) / np.linalg.norm(want))
    if cos < 0.95:
        sys.exit(f"the int8 export drifted: cosine {cos:.3f}")
print(f"wrote {out}")

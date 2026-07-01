import argparse

from datasets import load_dataset
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    TrainingArguments,
    Trainer,
)
from peft import LoraConfig, get_peft_model
import torch

MODEL_ID = "deepseek-ai/deepseek-coder-6.7b-instruct"
DEFAULT_INPUT = "data/merged_dataset.jsonl"


parser = argparse.ArgumentParser()
parser.add_argument("--input", default=DEFAULT_INPUT, help="Merged JSONL dataset to train on")
parser.add_argument("--output", default="outputs/lora_final", help="Directory for the trained adapter")
args = parser.parse_args()

dataset = load_dataset(
    "json",
    data_files=args.input,
    split="train",
)

dataset = dataset.filter(lambda example: bool(str(example.get("completion", "")).strip()))

tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)

if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

def preprocess(example):
    text = f"### Instruction:\n{example['prompt']}\n\n### Response:\n{example['completion']}"
    tokens = tokenizer(
        text,
        truncation=True,
        max_length=1024,
        padding="max_length",
    )
    tokens["labels"] = tokens["input_ids"].copy()
    return tokens

dataset = dataset.map(preprocess)

model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    torch_dtype=torch.float16,
    device_map="auto",
)

lora_config = LoraConfig(
    r=8,
    lora_alpha=16,
    target_modules=["q_proj", "v_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
)

model = get_peft_model(model, lora_config)

training_args = TrainingArguments(
    output_dir=args.output,
    num_train_epochs=3,
    per_device_train_batch_size=1,
    gradient_accumulation_steps=4,
    learning_rate=2e-4,
    logging_steps=10,
    save_strategy="epoch",
    fp16=True,
    report_to="none",
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=dataset,
)

trainer.train()

model.save_pretrained(args.output)
tokenizer.save_pretrained(args.output)

print("TRAINING_COMPLETE")
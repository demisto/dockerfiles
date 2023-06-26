from transformers import AutoModelForQuestionAnswering, AutoTokenizer

model_names = ['distilbert-base-cased-distilled-squad']
def main():
    for model in model_names:
        AutoModelForQuestionAnswering.from_pretrained(model)
        AutoTokenizer.from_pretrained(model)

if __name__ == "__main__":
    main()
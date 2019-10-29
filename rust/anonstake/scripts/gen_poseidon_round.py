if __name__ == "__main__":
    out = open("output/poseidon_round.txt", "w")
    with open("input/poseidon_round_constants.txt", "r") as f:
        for line in f:
            line = line[:-1]
            num = int(line, 0)
            template = "E::Fr::from_str(\"{}\").expect(\"failure generating constants\")"
            out.write(template.format(num) + ",\n")
    out.close()
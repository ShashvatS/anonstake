if __name__ == "__main__":
    with open("input/genmds.txt", "r") as f:
        for line in f:
            line = line[:-1]
            num = int(line, 0)
            numbin = bin(num)
            while len(numbin) != 257:
                numbin += "0"
            num = int(numbin, 0)
            if bin(num)[-6:] == "000000":
                template = "E::Fr::from_str(\"{}\").expect(\"failure generating constants\")"
                print(template.format(num))
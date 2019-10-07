if __name__ == "__main__":
    constants = []

    num_constants = 162
    format_string = "[{}]"
    if True:
        tmp = ''.join(['{' + "{}".format(str(i)) + "}, " for i in range(162)])
        tmp = tmp[:-2]
        format_string = format_string.format(tmp)

    with open("constants.txt", "r") as f:
        for line in f:
            constant = int(line, 0)
            template = "<Bls12 as ScalarEngine>::Fr::from_str(\"{}\").expect(\"failure generating constants\")"
            constants.append(template.format(constant))

    with open("mimc_constants.txt", "w") as f:
        i = 0
        while i < len(constants):
            line = "let x{} = ".format(i // 162) + format_string.format(*constants[i:i + 162]) + ";\n"
            f.write(line)
            i += 162


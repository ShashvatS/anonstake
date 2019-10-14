from mpmath import mp, mpf, log, exp

mp.prec = 80
numcoins = mpf(2**60 - 1)
negl = mpf(1.0) * pow(mpf(0.5), 80)

def log_nck(n, k):
    if k == 0 or k == n:
        return log(mpf(1))

    nint = n
    kint = k
    n = mpf(n)
    k = mpf(k)
    ans = mpf(0)
    for i in range(nint, nint - kint, -1):
        ans += log(mpf(i))
    for i in range(kint, 0, -1):
        ans -= log(mpf(i))
    return ans

def calc_prob(choose_i, from_n, prob):
    # probability = (nCk) * p**k * (1-p)**(n - k)
    log_ans = log_nck(from_n, choose_i) + mpf(choose_i) * log(prob)
    log_ans += (mpf(from_n - choose_i)) * log(mpf(1) - prob)
    return exp(log_ans)

def run1(prob, file):
    for i in range(0, 60):
        n = pow(2, i)

        cum_prob = calc_prob(0, n, prob)
        k = 0

        values = []

        while cum_prob < negl:
            k += 1
            cum_prob += calc_prob(k, n, prob)
        k1 = k

        while cum_prob < mpf(1.0) - negl and k < n:
            values.append((k, cum_prob))
            k += 1
            tmp = calc_prob(k, n, prob)
            cum_prob += tmp
            # print(cum_prob, end=" ")

        k2 = k
        print(k1, k2 - 1)

        template = "E::Fr::from_str(\"{}\").expect(\"failure generating constants\")"
        file.write(template.format(k1) + ",\n")

    values = [(x[0], int(x[1] * (mpf(2) ** 80))) for x in values]

if __name__ == "__main__":
    tau_vals = [1500, 2000, 2990, 5000]
    for tau in tau_vals:
        file = open("binomial_constants_1_{}.txt".format(tau), "w")
        prob = mpf(tau) / numcoins
        run1(prob, file)
        file.close()







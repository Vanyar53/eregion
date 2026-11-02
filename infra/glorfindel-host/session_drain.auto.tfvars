# SEC11 (R-03) : les VM du banc que Glorfindel défend et dont H0 coupe les sessions à l'isolation —
# « Eregion Glorfindel Session Drain » sur chacune, jamais sur le groupe (main.tf). Commité : chaque
# plan de H0 la relit, un `make glorfindel-host-up` ordinaire ne retire rien. Une VM ôtée d'ici perd
# la coupure au prochain apply (le plan le montre) ; isolée, la coupure y est refusée et dite.
session_drain_vms = ["vm-celebrimbor-gondolin", "vm-celebrimbor-bree"]

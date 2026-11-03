# SEC17 : les VM du banc que le restore défend — « Eregion Glorfindel Restore Neutralize » sur chacune,
# pour chaque principal de restore_principals (la console, le bot), jamais sur le groupe (main.tf).
# Commité : chaque plan de H0 la relit, un `make glorfindel-host-up` ordinaire ne retire rien. Une VM
# ôtée d'ici perd la neutralisation au prochain apply (le plan le montre) ; restaurée, elle l'est quand
# même, la neutralisation refusée et dite sur la carte.
restore_vms = ["vm-celebrimbor-gondolin", "vm-celebrimbor-bree"]

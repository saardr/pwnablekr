#include <stdio.h>
#include <stdlib.h>

int main() {
  int num, num2;
  char buffer[100];
  printf("please enter your name\n");
  scanf("%100s", buffer);
  printf("please enter num: ");
  scanf("%d", num);
  fflush(stdin);
  printf("please enter num2: ");
  scanf("%d", num2);
}
